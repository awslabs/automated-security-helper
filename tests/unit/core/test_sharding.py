# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the scan-sharding partition and coverage checks.

The partition is the load-bearing part: every executor computes it independently
with no coordination, so a rule that is not a pure function of (sorted names,
index, count) would let two executors disagree and silently drop a scanner. The
tests below therefore pin determinism, disjointness and completeness as
properties rather than checking one hand-picked split.
"""

import pytest

from automated_security_helper.core.sharding import (
    ShardAssignment,
    ShardCoverageError,
    ShardSelectionError,
    partition_scanners,
    scanners_to_exclude,
    validate_shard_selection,
    verify_shard_coverage,
)

# A deliberately unsorted list. Passing an already-sorted list would let a
# partition that depends on input order pass by accident.
SCANNERS = [
    "semgrep",
    "bandit",
    "checkov",
    "detect-secrets",
    "cdk-nag",
    "grype",
    "npm-audit",
    "cfn-nag",
    "syft",
    "opengrep",
]


class TestValidateShardSelection:
    def test_both_unset_is_allowed(self):
        # The overwhelmingly common case: no sharding at all.
        validate_shard_selection(None, None)

    @pytest.mark.parametrize(
        "index,count",
        [(0, None), (None, 2)],
    )
    def test_one_without_the_other_is_refused(self, index, count):
        # A lone --shard-index would otherwise scan shard 0 of an unknown total
        # and report a partial scan as a whole one.
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(index, count)

    @pytest.mark.parametrize("count", [0, -1])
    def test_non_positive_count_is_refused(self, count):
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(0, count)

    @pytest.mark.parametrize("index", [-1, 2, 99])
    def test_index_outside_the_count_is_refused(self, index):
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(index, 2)

    def test_single_shard_is_allowed(self):
        # count=1 is degenerate but legitimate: a pipeline that parameterises
        # shard count should not break when someone sets it to 1.
        validate_shard_selection(0, 1)


class TestPartitionScanners:
    @pytest.mark.parametrize("count", [1, 2, 3, 4, 7, 10])
    def test_shards_are_disjoint_and_cover_everything(self, count):
        shards = [partition_scanners(SCANNERS, i, count) for i in range(count)]

        flat = [name for shard in shards for name in shard]
        # Disjoint: no scanner runs twice, which would double-report its findings
        # after the merge, because merging does not dedupe.
        assert len(flat) == len(set(flat))
        # Complete: no scanner is dropped, which would silently narrow coverage.
        assert set(flat) == set(SCANNERS)

    @pytest.mark.parametrize("count", [2, 3, 5])
    def test_partition_is_deterministic_across_input_orderings(self, count):
        # Different executors may enumerate plugins in different orders (dict
        # ordering, plugin module load order). The split must not depend on it.
        shuffled = list(reversed(SCANNERS))
        for i in range(count):
            assert partition_scanners(SCANNERS, i, count) == partition_scanners(
                shuffled, i, count
            )

    def test_repeated_calls_agree(self):
        assert partition_scanners(SCANNERS, 1, 3) == partition_scanners(SCANNERS, 1, 3)

    def test_single_shard_gets_everything(self):
        assert partition_scanners(SCANNERS, 0, 1) == sorted(SCANNERS)

    def test_more_shards_than_scanners_leaves_some_empty(self):
        count = len(SCANNERS) + 3
        shards = [partition_scanners(SCANNERS, i, count) for i in range(count)]
        assert sum(1 for s in shards if not s) == 3
        # Still complete despite the empties.
        assert sorted(n for s in shards for n in s) == sorted(SCANNERS)

    def test_empty_scanner_list_yields_empty_shard(self):
        assert partition_scanners([], 0, 2) == []

    def test_duplicates_in_the_input_are_collapsed(self):
        # plugin_modules() can return the same scanner twice when a module is
        # registered under two names. Keeping both would run it twice in one
        # shard, or once in two shards.
        assert partition_scanners(["bandit", "bandit", "semgrep"], 0, 1) == [
            "bandit",
            "semgrep",
        ]

    def test_sizes_are_balanced_to_within_one(self):
        sizes = [len(partition_scanners(SCANNERS, i, 3)) for i in range(3)]
        assert max(sizes) - min(sizes) <= 1


class TestScannersToExclude:
    def test_excludes_exactly_the_unassigned(self):
        assigned = partition_scanners(SCANNERS, 0, 2)
        excluded = scanners_to_exclude(SCANNERS, assigned)
        assert set(assigned).isdisjoint(excluded)
        assert set(assigned) | set(excluded) == set(SCANNERS)

    def test_operator_exclusions_are_preserved(self):
        # --exclude-scanners must survive sharding; dropping it would run a
        # scanner the operator deliberately turned off.
        assigned = partition_scanners(SCANNERS, 0, 2)
        excluded = scanners_to_exclude(
            SCANNERS, assigned, already_excluded=["semgrep", "SYFT"]
        )
        assert "semgrep" in excluded
        # Case-insensitive: the CLI lowercases scanner names when matching.
        assert "syft" in excluded

    def test_result_is_sorted_and_deduplicated(self):
        excluded = scanners_to_exclude(
            SCANNERS, ["bandit"], already_excluded=["semgrep", "semgrep"]
        )
        assert excluded == sorted(set(excluded))


class TestVerifyShardCoverage:
    def _assignments(self, count, names=SCANNERS):
        return [
            ShardAssignment(
                shard_index=i,
                shard_count=count,
                assigned_scanners=partition_scanners(names, i, count),
            )
            for i in range(count)
        ]

    def test_a_complete_set_passes(self):
        verify_shard_coverage(self._assignments(3))

    def test_a_missing_shard_is_refused(self):
        assignments = self._assignments(3)
        del assignments[1]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        # The message must name the gap; "merge failed" alone leaves the
        # operator to guess which job did not upload its artifact.
        assert "1" in str(excinfo.value)

    def test_a_duplicate_shard_is_refused(self):
        assignments = self._assignments(3)
        assignments.append(assignments[0])
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_a_duplicate_empty_shard_is_refused(self):
        # Isolates the duplicate-index check from the scanner-overlap check.
        # Duplicating a *populated* shard trips both, so it does not prove the
        # index check works. Empty shards are not hypothetical: any shard count
        # above the scanner count produces them, and collecting one job's
        # artifact twice has to be refused even when it claims no scanners.
        count = len(SCANNERS) + 2
        assignments = self._assignments(count)
        empties = [a for a in assignments if not a.assigned_scanners]
        assert empties, "expected surplus shards to be empty"
        assignments.append(empties[0])
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "more than once" in str(excinfo.value)

    def test_disagreeing_shard_counts_are_refused(self):
        # Two jobs from different runs, or a pipeline whose shard count changed
        # mid-flight. Merging them would produce a report missing whole scanners
        # while looking structurally fine.
        assignments = self._assignments(3)
        assignments[2] = ShardAssignment(
            shard_index=2, shard_count=4, assigned_scanners=["syft"]
        )
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_a_scanner_claimed_by_two_shards_is_refused(self):
        assignments = self._assignments(2)
        assignments[1].assigned_scanners.append(assignments[0].assigned_scanners[0])
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_empty_input_is_refused(self):
        # Nothing to merge is a failure, not a clean empty report: an empty
        # report reads as "no findings".
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage([])
