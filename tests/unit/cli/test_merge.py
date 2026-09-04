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
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import (
    MERGED_SHARD_COUNT_KEY,
    MERGED_SHARD_INDICES_KEY,
    RESULTS_FILE_NAME,
    SHARD_PROVENANCE_KEY,
    _merged_exit_code,
    apply_aggregated_suppressions,
    load_shard_results,
    merge_shard_results,
    read_shard_assignment,
    resolve_results_file,
    stamp_shard_assignment,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ShardCoverageError
from automated_security_helper.core.sharding import (
    ShardAssignment,
    partition_scanners,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

# A deliberately unsorted scanner list, so a partition that depended on input
# order could not pass by accident, and one scanner with no findings so the
# "clean scanner still has to appear" case is covered.
SCANNERS = ["semgrep", "bandit", "grype", "checkov", "detect-secrets"]

# scanner -> [(sarif level, issue_severity)]. Only checkov and bandit carry
# anything actionable at the default MEDIUM threshold; semgrep's single LOW
# finding is the case that must be counted as a finding but not as actionable.
FINDINGS: Dict[str, List[Tuple[str, str]]] = {
    "bandit": [("error", "HIGH"), ("warning", "MEDIUM")],
    "checkov": [("error", "CRITICAL")],
    "semgrep": [("note", "LOW")],
    "grype": [],
    "detect-secrets": [("warning", "MEDIUM")],
}


#: A tool component every shard reports, unlike the per-scanner ones. Real
#: aggregates carry components that are not one-per-scanner -- ASH's own driver
#: ends up in extensions once merging starts -- so the union has to cope with the
#: same component arriving from several shards with different rules.
SHARED_COMPONENT = ("ash-core", "ASH core rules", "test")


def _build_config(fail_on_findings=None, suppressions=None):
    """A minimal real AshConfig.

    Supplied rather than left as None because ``AshAggregatedResults`` logs a
    validation error for a None config on every construction, and because
    ``_compute_exit_code`` reads ``global_settings.severity_threshold`` off it --
    a test with no config would exercise a default that no real scan uses.

    ``suppressions`` defaults to none, and that default is why the equivalence
    property in ``TestShardedEqualsUnsharded`` passed while ``ash merge`` never
    applied the aggregated suppression pass at all: with no suppression in the
    config, both paths agree no matter which one skips the pass.
    ``TestSuppressionsAcrossShards`` supplies some.
    """
    from automated_security_helper.config.ash_config import (
        AshConfig,
        AshConfigGlobalSettingsSection,
    )

    config = AshConfig(
        project_name="test-merge",
        global_settings=AshConfigGlobalSettingsSection(
            severity_threshold="MEDIUM",
            suppressions=list(suppressions or []),
        ),
    )
    if fail_on_findings is not None:
        config.fail_on_findings = fail_on_findings
    return config


def _sarif_result(scanner: str, index: int, level: str, severity: str) -> Result:
    return Result(
        ruleId=f"{scanner}-RULE-{index}",
        level=Level(level),
        message=Message(root=Message1(text=f"{scanner} finding {index}")),
        properties=PropertyBag(scanner_name=scanner, issue_severity=severity),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(
                            uri=f"src/{scanner}_{index}.py"
                        ),
                        region=Region(startLine=index + 1),
                    )
                )
            )
        ],
    )


def _sarif_for(scanners: Sequence[str]) -> SarifReport:
    """Build the SARIF a scan of *scanners* would produce.

    Each scanner contributes a tool component under ``extensions`` carrying its
    rules, which is the shape a real ASH aggregate has and the shape that would
    silently lose rule metadata if merging only handled ``tool.driver``.
    """
    results: List[Result] = []
    extensions: List[ToolComponent] = []
    for scanner in scanners:
        rules = []
        for index, (level, severity) in enumerate(FINDINGS[scanner]):
            results.append(_sarif_result(scanner, index, level, severity))
            rules.append(ReportingDescriptor(id=f"{scanner}-RULE-{index}"))
        extensions.append(
            ToolComponent(
                name=scanner,
                fullName=f"{scanner} scanner",
                organization="test",
                rules=rules,
            )
        )
    # One component with a stable identity across every shard, carrying a
    # different rule per shard. Merging must keep one copy of the component and
    # the union of its rules; appending blindly would produce n copies, and
    # keeping only the first would lose the other shards' rules.
    name, full_name, organization = SHARED_COMPONENT
    extensions.append(
        ToolComponent(
            name=name,
            fullName=full_name,
            organization=organization,
            rules=[ReportingDescriptor(id=f"shared-{scanner}") for scanner in scanners],
        )
    )
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name="ASH", version="test"),
                    extensions=extensions,
                ),
                results=results,
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )


def _ran_entries(model: AshAggregatedResults, scanner: str) -> None:
    """Record *scanner* on *model* as a scanner this executor actually ran."""
    model.scanner_results[scanner] = ScannerTargetStatusInfo(
        status=ScannerStatus.FAILED if FINDINGS[scanner] else ScannerStatus.PASSED,
        excluded=False,
        dependencies_satisfied=True,
    )
    model.additional_reports[scanner] = {
        "source": {
            "scanner_name": scanner,
            "status": "FAILED" if FINDINGS[scanner] else "PASSED",
            "duration": 2.0,
        }
    }


def _skipped_entries(model: AshAggregatedResults, scanner: str) -> None:
    """Record *scanner* the way a shard records a scanner it did not own.

    Both halves matter. ``ScanPhase`` writes the ``scanner_results`` entry, and
    ``_process_results`` writes the ``additional_reports[name]["None"]`` marker --
    and it is the marker that ``get_scanner_status_info`` consults first, so a
    fixture that only wrote the ``scanner_results`` half would let a broken merge
    pass.
    """
    model.scanner_results[scanner] = ScannerStatusInfo(
        status=ScannerStatus.SKIPPED, excluded=True, dependencies_satisfied=True
    )
    model.additional_reports[scanner] = {
        "None": {"scanner_name": scanner, "status": "SKIPPED", "excluded": True}
    }


def build_shard(
    shard_index: int,
    shard_count: int,
    owned: Sequence[str],
    all_scanners: Sequence[str] = SCANNERS,
    stamp: bool = True,
    suppressions=None,
) -> AshAggregatedResults:
    """Build the results one shard of a sharded scan would write.

    The SARIF this produces is never pre-suppressed, whatever ``suppressions``
    says. That is deliberate and it is the state a real shard is in when a
    suppression's path only becomes matchable after merge and normalization: the
    shard carries the config, its own per-scanner pass did not match, and the
    aggregated pass on the merged product is the only thing left that can.
    """
    model = AshAggregatedResults()
    model.ash_config = _build_config(suppressions=suppressions)
    # Distinct per shard so it is observable which shard supplied the merged
    # report's identity. Without something base-dependent in the fixture, a merge
    # that took its base from whichever shard happened to be listed first would
    # be indistinguishable from one that took the lowest index.
    model.name = f"shard-{shard_index} scan"
    model.sarif = _sarif_for(owned)
    for scanner in all_scanners:
        if scanner in owned:
            _ran_entries(model, scanner)
        else:
            _skipped_entries(model, scanner)
    model.metadata.summary_stats.start = f"2026-08-28T10:{shard_index:02d}:00"
    model.metadata.summary_stats.end = f"2026-08-28T10:{shard_index + 20:02d}:00"
    model.metadata.summary_stats.duration = 60.0 + shard_index
    if stamp:
        stamp_shard_assignment(
            model,
            ShardAssignment(
                shard_index=shard_index,
                shard_count=shard_count,
                assigned_scanners=list(owned),
                # Recorded because a real ScanPhase records it. Fixtures that left
                # it None would exercise only the backward-compatibility path, in
                # which verify_shard_coverage skips the union check entirely -- so
                # the mainline merge tests would run against a weaker contract than
                # any real scan produces.
                candidate_scanners=list(all_scanners),
            ),
        )
    return model


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


def build_shards(shard_count: int = 3, suppressions=None) -> List[AshAggregatedResults]:
    """Build every shard of a *shard_count*-way split of the same tree."""
    return [
        build_shard(
            index,
            shard_count,
            partition_scanners(SCANNERS, index, shard_count),
            suppressions=suppressions,
        )
        for index in range(shard_count)
    ]


def write_shards(
    tmp_path: Path, models: Sequence[AshAggregatedResults], as_dirs: bool = True
) -> List[str]:
    """Write each shard's results out the way a CI job's artifact would land."""
    paths: List[str] = []
    for index, model in enumerate(models):
        target = tmp_path / f"shard-{index}"
        target.mkdir(parents=True, exist_ok=True)
        results_file = target / RESULTS_FILE_NAME
        results_file.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        paths.append(str(target if as_dirs else results_file))
    return paths


def as_loaded(
    models: Sequence[AshAggregatedResults],
) -> List[Tuple[Path, AshAggregatedResults]]:
    """Pair models with placeholder paths, for tests that skip disk entirely."""
    return [(Path(f"shard-{index}.json"), model) for index, model in enumerate(models)]


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
        # Parity with `ash scan --min-severity`. The gate in _compute_exit_code
        # reads the SARIF *level*, not issue_severity, so downgrading every
        # finding to warning puts them all at medium: actionable against the
        # config's MEDIUM threshold, but below a critical floor. Without
        # min_severity reaching _compute_exit_code both floors would answer 2,
        # and the second answer would be wrong.
        shards = build_shards(3)
        for model in shards:
            for result in model.sarif.runs[0].results:
                result.level = "warning"
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
        # would pin another command's quirk into this lane's tests.
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

    def test_the_same_shards_merge_without_the_flag(self, tmp_path):
        """The default half of the pair, through the same CLI path."""
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(tmp_path / "merged"), "--output-formats", "sarif"]

        result = self._invoke(args)

        # 2 for the other shards' findings, and the merged report exists. This is
        # today's behaviour and it stays.
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

    def test_the_default_still_merges_a_shard_that_completed_nothing(self, tmp_path):
        """The defect, and the behaviour the default has to preserve.

        Every finding is stripped so the only signal left is completeness. One of
        three shards ran nothing, and the merge reports a clean scan -- exit 0,
        the same code a genuinely clean three-shard scan produces. That is the
        distributed false green, and it is what the gate has to be *opt-in*
        against: refusing here by default would break merges in every
        environment that legitimately lacks a scanner's tool.
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

        assert _merged_exit_code(merged, tmp_path, "low", None) == 0

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

    def test_the_default_is_unchanged_by_an_incomplete_scanner(self, tmp_path):
        merged = merge_shard_results(
            as_loaded(self._shards_with_one_incomplete_scanner())
        )

        # 2 for the findings the other scanners did report; the incomplete grype
        # is invisible to the default verdict, exactly as it was before.
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
